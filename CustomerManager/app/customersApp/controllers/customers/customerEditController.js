﻿(function () {

    var injectParams = ['$scope', '$location', '$routeParams', 
                        '$timeout', 'config', 'dataService', 'modalService', '$http'];

    var CustomerEditController = function ($scope, $location, $routeParams,
                                           $timeout, config, dataService, modalService, $http) {

        var customerId = ($routeParams.customerId) ? parseInt($routeParams.customerId) : 0,
            timer,
            onRouteChangeOff;

        $scope.customer = {};
        $scope.states = [];
        $scope.title = (customerId > 0) ? 'Edit' : 'Add';
        $scope.buttonText = (customerId > 0) ? 'Update' : 'Add';
        $scope.updateStatus = false;
        $scope.errorMessage = '';


        $scope.spaces = [];

        var token = getCookie('user.token');

        if(token){
            $http.get('/api/kona/spaces')
            .success(function(data, status, headers, config) {
                $scope.spaces = data.spaces;
                console.log("Kona API Spaces", $scope.spaces);
            })
        }
        

        $scope.isStateSelected = function (customerStateId, stateId) {
            return customerStateId === stateId;
        };

        $scope.saveCustomer = function () {
            if ($scope.editForm.$valid) {
                if (!$scope.customer.id) {
                    dataService.insertCustomer($scope.customer).then(processSuccess, processError);
                }
                else {
                    dataService.updateCustomer($scope.customer).then(processSuccess, processError);
                }
            }
        };

        $scope.deleteCustomer = function () {
            var custName = $scope.customer.firstName + ' ' + $scope.customer.lastName;
            var modalOptions = {
                closeButtonText: 'Cancel',
                actionButtonText: 'Delete Customer',
                headerText: 'Delete ' + custName + '?',
                bodyText: 'Are you sure you want to delete this customer?'
            };

            modalService.showModal({}, modalOptions).then(function (result) {
                if (result === 'ok') {
                    dataService.deleteCustomer($scope.customer.id).then(function () {
                        onRouteChangeOff(); //Stop listening for location changes
                        $location.path('/customers');
                    }, processError);
                }
            });
        };

        function init() {

            getStates();

            if (customerId > 0) {
                dataService.getCustomer(customerId).then(function (customer) {
                    $scope.customer = customer;
                    if(typeof customer.space !== "undefined")
                        changeKonaSpace(customer.space);
                    else
                        changeKonaSpace(-1);
                }, processError);
            } else {
                dataService.newCustomer().then(function (customer) {
                    $scope.customer = customer;
                    changeKonaSpace(-1);
                });

            }

            //Make sure they're warned if they made a change but didn't save it
            //Call to $on returns a "deregistration" function that can be called to
            //remove the listener (see routeChange() for an example of using it)
            onRouteChangeOff = $scope.$on('$locationChangeStart', routeChange);
        }

        init();

        function routeChange(event, newUrl, oldUrl) {
            //Navigate to newUrl if the form isn't dirty
            if (!$scope.editForm || !$scope.editForm.$dirty) return;

            var modalOptions = {
                closeButtonText: 'Cancel',
                actionButtonText: 'Ignore Changes',
                headerText: 'Unsaved Changes',
                bodyText: 'You have unsaved changes. Leave the page?'
            };

            modalService.showModal({}, modalOptions).then(function (result) {
                if (result === 'ok') {
                    onRouteChangeOff(); //Stop listening for location changes
                    $location.path($location.url(newUrl).hash()); //Go to page they're interested in
                }
            });

            //prevent navigation by default since we'll handle it
            //once the user selects a dialog option
            event.preventDefault();
            return;
        }

        function getStates() {
            dataService.getStates().then(function (states) {
                $scope.states = states;
            }, processError);
        }

        function processSuccess() {
            $scope.editForm.$dirty = false;
            $scope.updateStatus = true;
            $scope.title = 'Edit';
            $scope.buttonText = 'Update';
            startTimer();
        }

        function processError(error) {
            $scope.errorMessage = error.message;
            startTimer();
        }

        function startTimer() {
            timer = $timeout(function () {
                $timeout.cancel(timer);
                $scope.errorMessage = '';
                $scope.updateStatus = false;
            }, 3000);
        }
    };

    CustomerEditController.$inject = injectParams;

    angular.module('customersApp').controller('CustomerEditController', CustomerEditController)
    
}());